# frozen_string_literal: true

require "openssl"
require "resolv"

module LegacyAPI
  class DomainsController < BaseController
    before_action :load_server!

    def create
      name = params[:name].to_s.strip.downcase
      return render json: { status: "error", message: "Domain name is required" }, status: 422 if name.empty?

      domain = Domain.find_by(name: name)

      if domain
        attach_server_if_missing(domain)
        return render json: { status: "success", data: serialize_domain(domain) }
      end

      domain = Domain.new
      domain.name = name
      domain.server = @server if domain.respond_to?(:server=)

      domain.verification_method = "DNS" if domain.respond_to?(:verification_method=)

      if domain.respond_to?(:owner_type=) && domain.respond_to?(:owner_id=)
        domain.owner_type = "Server"
        domain.owner_id = @server.id
      end

      if domain.save
        render json: { status: "success", data: serialize_domain(domain) }
      else
        render json: { status: "error", message: domain.errors.full_messages.join(", ") }, status: 422
      end
    end

    def query
      name = params[:name].to_s.strip.downcase
      return render json: { status: "error", message: "Domain name is required" }, status: 422 if name.empty?

      domain = Domain.find_by(name: name)
      return render json: { status: "error", message: "Domain not found" }, status: 404 unless domain

      attach_server_if_missing(domain)

      render json: { status: "success", data: serialize_domain(domain) }
    end

    def check
      name = params[:name].to_s.strip.downcase
      return render json: { status: "error", message: "Domain name is required" }, status: 422 if name.empty?

      domain = Domain.find_by(name: name)
      return render json: { status: "error", message: "Domain not found" }, status: 404 unless domain

      attach_server_if_missing(domain)

      dns = dns_check(domain)

      if domain.respond_to?(:dns_checked_at=)
        domain.dns_checked_at = Time.now
        begin
          domain.save(validate: false)
        rescue
        end
      end

      render json: { status: "success", data: serialize_domain(domain, include_dns: true, dns_result: dns) }
    end

    def delete
      name = params[:name].to_s.strip.downcase
      return render json: { status: "error", message: "Domain name is required" }, status: 422 if name.empty?

      domain = Domain.find_by(name: name)
      return render json: { status: "error", message: "Domain not found" }, status: 404 unless domain

      domain.destroy
      render json: { status: "success", data: { message: "Domain deleted" } }
    end

    private

    def load_server!
      key = request.headers["X-Server-API-Key"].to_s.strip
      return render json: { status: "error", message: "Missing X-Server-API-Key" }, status: 401 if key.empty?

      cred = nil
      if defined?(Credential)
        begin
          cred = Credential.find_by(key: key)
        rescue
          cred = nil
        end
      end

      unless cred && cred.respond_to?(:server_id) && cred.server_id
        return render json: { status: "error", message: "Invalid API key" }, status: 401
      end

      @server = Server.find_by(id: cred.server_id)
      return render json: { status: "error", message: "Server not found for API key" }, status: 401 unless @server
    end

    def attach_server_if_missing(domain)
      return unless domain.respond_to?(:server_id) && domain.respond_to?(:server_id=)

      if domain.server_id.nil?
        begin
          domain.update_column(:server_id, @server.id)
        rescue
          begin
            domain.server_id = @server.id
            domain.save(validate: false)
          rescue
          end
        end
      end
    end

    def serialize_domain(domain, include_dns: false, dns_result: nil)
      out = {
        id: domain.id,
        name: domain.name,
        server_id: domain.respond_to?(:server_id) ? domain.server_id : nil
      }

      out[:verification_method] = domain.verification_method if domain.respond_to?(:verification_method)

      out[:created_at] = domain.created_at if domain.respond_to?(:created_at)
      out[:updated_at] = domain.updated_at if domain.respond_to?(:updated_at)

      out[:return_path_domain] = domain.return_path_domain if domain.respond_to?(:return_path_domain)
      out[:dkim_identifier] = domain.dkim_identifier if domain.respond_to?(:dkim_identifier)

      out[:dkim_key] = {}

      out[:verified] = domain.verified? if domain.respond_to?(:verified?)
      out[:verified_at] = domain.verified_at if domain.respond_to?(:verified_at)
      out[:dns_checked_at] = domain.dns_checked_at if domain.respond_to?(:dns_checked_at)

      if dns_result
        out[:dns_ok] = dns_result[:dns_ok]
        out[:spf_ok] = dns_result[:spf_ok]
        out[:dkim_ok] = dns_result[:dkim_ok]
        out[:return_path_ok] = dns_result[:return_path_ok]
        out[:mx_ok] = dns_result[:mx_ok]
      end

      out[:dns] = dns_payload(domain, dns_result) if include_dns

      out
    end

    def dns_payload(domain, dns_result)
      spf_expected = "v=spf1 a mx include:spf.mail.yournotify.net ~all"

      dkim_host = nil
      if domain.respond_to?(:dkim_identifier) && domain.dkim_identifier.to_s.strip != ""
        dkim_host = "#{domain.dkim_identifier}._domainkey.#{domain.name}"
      end

      rp_host = domain.respond_to?(:return_path_domain) ? domain.return_path_domain : nil
      rp_expected = "rp.mail.yournotify.net"

      verify_host = "postal-verification.#{domain.name}"
      verify_value = domain.respond_to?(:dns_verification_string) ? domain.dns_verification_string.to_s : nil

      dkim_value = dkim_txt_value(domain)

      payload = {
        ownership: {
          host: verify_host,
          value: verify_value
        },
        spf: {
          expected: spf_expected
        },
        dkim: {
          host: dkim_host,
          value: dkim_value
        },
        return_path: {
          host: rp_host,
          expected_target: rp_expected
        }
      }

      if dns_result
        payload[:spf][:found] = dns_result[:spf_found]
        payload[:dkim][:found] = dns_result[:dkim_found]
        payload[:return_path][:found] = dns_result[:return_path_found]
        payload[:ownership][:found] = dns_result[:ownership_found]
      end

      payload
    end

    def dns_check(domain)
      resolver = Resolv::DNS.new

      name = domain.name.to_s.strip.downcase
      spf_txts = txt_records(resolver, name)
      spf_ok = spf_txts.any? { |t| t.include?("include:spf.mail.yournotify.net") }
      spf_found = spf_txts

      dkim_host = nil
      dkim_expected = dkim_txt_value(domain)
      dkim_ok = false
      dkim_found = []

      if domain.respond_to?(:dkim_identifier) && domain.dkim_identifier.to_s.strip != ""
        dkim_host = "#{domain.dkim_identifier}._domainkey.#{name}"
        dkim_found = txt_records(resolver, dkim_host)
        if dkim_expected && dkim_expected.to_s.strip != ""
          exp_p = dkim_expected.split("p=").last.to_s.strip
          dkim_ok = dkim_found.any? { |t| t.include?("p=#{exp_p}") }
        end
      end

      rp_host = domain.respond_to?(:return_path_domain) ? domain.return_path_domain.to_s.strip.downcase : nil
      rp_expected = "rp.mail.yournotify.net"
      return_path_ok = false
      return_path_found = nil

      if rp_host && rp_host != ""
        return_path_found = cname_target(resolver, rp_host)
        return_path_ok = normalize_dns_name(return_path_found) == normalize_dns_name(rp_expected)
      end

      ownership_host = "postal-verification.#{name}"
      ownership_value = domain.respond_to?(:dns_verification_string) ? domain.dns_verification_string.to_s.strip : ""
      ownership_found = txt_records(resolver, ownership_host)
      ownership_ok = ownership_value != "" && ownership_found.any? { |t| t.strip == ownership_value }

      mx_ok = nil

      dns_ok = spf_ok && dkim_ok && return_path_ok

      {
        dns_ok: dns_ok,
        spf_ok: spf_ok,
        dkim_ok: dkim_ok,
        return_path_ok: return_path_ok,
        mx_ok: mx_ok,
        spf_found: spf_found,
        dkim_found: dkim_found,
        return_path_found: return_path_found,
        ownership_found: ownership_found,
        ownership_ok: ownership_ok
      }
    rescue
      {
        dns_ok: false,
        spf_ok: false,
        dkim_ok: false,
        return_path_ok: false,
        mx_ok: nil,
        spf_found: [],
        dkim_found: [],
        return_path_found: nil,
        ownership_found: [],
        ownership_ok: false
      }
    end

    def txt_records(resolver, host)
      resolver.getresources(host, Resolv::DNS::Resource::IN::TXT).map do |r|
        if r.data.is_a?(Array)
          r.data.join
        else
          r.data.to_s
        end
      end
    rescue
      []
    end

    def cname_target(resolver, host)
      r = resolver.getresources(host, Resolv::DNS::Resource::IN::CNAME).first
      return nil unless r
      r.name.to_s
    rescue
      nil
    end

    def normalize_dns_name(s)
      s.to_s.strip.downcase.sub(/\.\z/, "")
    end

    def dkim_txt_value(domain)
      return nil unless domain.respond_to?(:dkim_key)

      priv = domain.dkim_key.to_s
      return nil if priv.strip == ""

      rsa = OpenSSL::PKey::RSA.new(priv)
      pub_pem = rsa.public_key.to_pem

      b64 = pub_pem
        .gsub("-----BEGIN PUBLIC KEY-----", "")
        .gsub("-----END PUBLIC KEY-----", "")
        .gsub(/\s+/, "")

      "v=DKIM1; t=s; h=sha256; p=#{b64}"
    rescue
      nil
    end
  end
end
