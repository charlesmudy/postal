# frozen_string_literal: true

require "openssl"
require "resolv"

module LegacyAPI
  class DomainsController < BaseController
    before_action :load_server!

    def create
      name = params[:name].to_s.strip.downcase

      if name.empty?
        return render json: { status: "error", message: "Domain name is required" }, status: 422
      end

      domain = Domain.find_by(name: name, server_id: @server.id)
      if domain
        return render json: { status: "success", data: serialize_domain(domain) }
      end

      domain = Domain.new
      domain.server = @server
      domain.name = name

      if domain.respond_to?(:verification_method=)
        domain.verification_method = "DNS"
      end

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
      domain = Domain.find_by(name: name, server_id: @server.id)

      unless domain
        return render json: { status: "error", message: "Domain not found" }, status: 404
      end

      render json: { status: "success", data: serialize_domain(domain) }
    end

    def check
      name = params[:name].to_s.strip.downcase
      domain = Domain.find_by(name: name, server_id: @server.id)

      unless domain
        return render json: { status: "error", message: "Domain not found" }, status: 404
      end

      # Force a DNS refresh using Postal's own methods
      begin
        if domain.respond_to?(:check_dns)
          begin
            domain.check_dns(:manual)
          rescue
            domain.check_dns
          end
        end
      rescue
      end

      render json: { status: "success", data: serialize_domain(domain, include_dns: true, include_flags: true) }
    end

    def delete
      name = params[:name].to_s.strip.downcase
      domain = Domain.find_by(name: name, server_id: @server.id)

      unless domain
        return render json: { status: "error", message: "Domain not found" }, status: 404
      end

      domain.destroy
      render json: { status: "success", data: { message: "Domain deleted" } }
    end

    private

    def load_server!
      key = request.headers["X-Server-API-Key"].to_s.strip
      if key.empty?
        return render json: { status: "error", message: "Missing X-Server-API-Key" }, status: 401
      end

      cred = nil
      if defined?(Credential)
        begin
          cred = Credential.where(key: key).first
        rescue
          cred = nil
        end
      end

      unless cred && cred.respond_to?(:server_id) && cred.server_id
        return render json: { status: "error", message: "Invalid API key" }, status: 401
      end

      @server = Server.find_by(id: cred.server_id)
      unless @server
        return render json: { status: "error", message: "Server not found" }, status: 401
      end
    end

    def serialize_domain(domain, include_dns: false, include_flags: false)
      out = {
        id: domain.id,
        name: domain.name,
        server_id: domain.server_id
      }

      out[:verification_method] = domain.verification_method if domain.respond_to?(:verification_method)
      out[:created_at] = domain.created_at if domain.respond_to?(:created_at)
      out[:updated_at] = domain.updated_at if domain.respond_to?(:updated_at)

      if domain.respond_to?(:verified?)
        out[:verified] = domain.verified?
      end
      out[:verified_at] = domain.verified_at if domain.respond_to?(:verified_at)
      out[:dns_checked_at] = domain.dns_checked_at if domain.respond_to?(:dns_checked_at)

      out[:return_path_domain] = domain.return_path_domain if domain.respond_to?(:return_path_domain)
      out[:dkim_identifier] = domain.dkim_identifier if domain.respond_to?(:dkim_identifier)

      # Keep shape similar to Postal API output you posted
      out[:dkim_key] = {}

      if include_flags
        out[:dns_ok] = safe_call(domain, :dns_ok?)
        out[:spf_ok] = safe_call(domain, :check_spf_record!)
        out[:dkim_ok] = safe_call(domain, :check_dkim_record!)
        out[:return_path_ok] = safe_call(domain, :check_return_path_record!)
        out[:mx_ok] = safe_call(domain, :check_mx_records!)
      end

      if include_dns
        out[:dns] = build_dns_payload(domain)
      end

      out
    end

    def safe_call(obj, method_name)
      return nil unless obj.respond_to?(method_name)
      begin
        v = obj.public_send(method_name)
        !!v
      rescue
        nil
      end
    end

    def build_dns_payload(domain)
      name = domain.name.to_s

      spf_expected = "v=spf1 a mx include:spf.mail.yournotify.net ~all"

      # IMPORTANT: Postal's UI expects postal-<dkim_identifier>._domainkey.<domain>
      dkim_host = nil
      if domain.respond_to?(:dkim_identifier) && domain.dkim_identifier.to_s.strip != ""
        dkim_host = "postal-#{domain.dkim_identifier}._domainkey.#{name}"
      end

      dkim_value = dkim_txt_value(domain)

      rp_host = domain.respond_to?(:return_path_domain) ? domain.return_path_domain : nil
      rp_expected = "rp.mail.yournotify.net"

      ownership_host = "postal-verification.#{name}"
      ownership_value = nil
      ownership_found = []
      if domain.respond_to?(:dns_verification_string)
        begin
          ownership_value = domain.dns_verification_string
        rescue
          ownership_value = nil
        end
      end

      {
        ownership: {
          host: ownership_host,
          value: ownership_value,
          found: ownership_found
        },
        spf: { expected: spf_expected },
        dkim: { host: dkim_host, value: dkim_value },
        return_path: { host: rp_host, expected_target: rp_expected }
      }
    end

    # Never return the private key. Return a DKIM TXT value built from the public key.
    def dkim_txt_value(domain)
      return nil unless domain.respond_to?(:dkim_key)

      priv = domain.dkim_key.to_s
      return nil if priv.strip == ""

      begin
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
end
