# frozen_string_literal: true

module LegacyAPI
  class DomainsController < BaseController

    # Master override:
    # - If X-Postal-Master-Key matches ENV["POSTAL_MASTER_API_KEY"],
    #   requests may operate across all servers in this Postal instance.
    # - Otherwise, everything remains scoped to @server from X-Server-API-Key.
    def master_override?
      master = request.headers["X-Postal-Master-Key"].to_s.strip
      env_key = ENV["POSTAL_MASTER_API_KEY"].to_s.strip
      return false if master.empty? || env_key.empty?
      ActiveSupport::SecurityUtils.secure_compare(master, env_key)
    end

    def scope_server
      return @server unless master_override?

      sid = params[:server_id].to_s.strip
      return @server if sid.empty?

      Server.find_by(id: sid) || @server
    end

    def find_domain_by_name(name)
      if master_override?
        Domain.find_by(name: name)
      else
        Domain.find_by(name: name, server: @server)
      end
    end

    def serialize_domain(domain)
      {
        id: domain.id,
        name: domain.name,
        server_id: domain.server_id,
        verification_method: domain.verification_method,
        created_at: domain.created_at&.iso8601,
        updated_at: domain.updated_at&.iso8601,
        return_path_domain: (domain.return_path_domain rescue nil),
        dkim_identifier: (domain.dkim_identifier rescue nil),
        dkim_key: {}
      }.compact
    end

    def serialize_dns(domain)
      expected_spf = "v=spf1 a mx include:spf.mail.yournotify.net ~all"

      dkim_host = nil
      dkim_value = nil

      begin
        dkim_host = "#{domain.dkim_identifier}._domainkey"
      rescue
      end

      begin
        # Postal stores a private key internally, UI shows public TXT value derived from it.
        # For your API response, returning the key body is optional.
        dkim_value = domain.dkim_key.to_s
      rescue
      end

      rp_host = nil
      begin
        rp_host = domain.return_path_domain
      rescue
      end

      {
        spf: {
          expected: expected_spf
        },
        dkim: {
          host: dkim_host,
          value: dkim_value
        }.compact,
        return_path: {
          host: rp_host,
          expected_target: "rp.mail.yournotify.net"
        }.compact
      }.compact
    end

    def create
      name = params[:name].to_s.strip.downcase

      if name.empty?
        render json: { status: "error", message: "Domain name is required" }, status: 422
        return
      end

      existing = find_domain_by_name(name)
      if existing
        render json: { status: "success", data: serialize_domain(existing) }
        return
      end

      s = scope_server

      domain = Domain.new
      domain.server = s
      domain.name = name

      # Must match Domain::VERIFICATION_METHODS inclusion validation
      domain.verification_method = "DNS"

      # These exist in your codebase (domains_api_controller.rb uses them)
      if domain.respond_to?(:owner_type=) && domain.respond_to?(:owner_id=)
        domain.owner_type = "Server"
        domain.owner_id = s.id
      end

      # Optional auto-verified behavior. If you want UI to still show unverified until DNS passes, remove this.
      domain.verified_at = Time.now if domain.respond_to?(:verified_at=)

      if domain.save
        render json: { status: "success", data: serialize_domain(domain) }
      else
        render json: { status: "error", message: domain.errors.full_messages.join(", ") }, status: 422
      end
    end

    def query
      name = params[:name].to_s.strip.downcase
      domain = find_domain_by_name(name)

      unless domain
        render json: { status: "error", message: "Domain not found" }, status: 404
        return
      end

      render json: { status: "success", data: serialize_domain(domain) }
    end

    def check
      name = params[:name].to_s.strip.downcase
      domain = find_domain_by_name(name)

      unless domain
        render json: { status: "error", message: "Domain not found" }, status: 404
        return
      end

      # Kick off Postal DNS checks, then return expected records payload
      domain.check_dns(:manual) if domain.respond_to?(:check_dns)

      render json: {
        status: "success",
        data: serialize_domain(domain).merge(dns: serialize_dns(domain))
      }
    end

    def delete
      name = params[:name].to_s.strip.downcase
      domain = find_domain_by_name(name)

      unless domain
        render json: { status: "error", message: "Domain not found" }, status: 404
        return
      end

      domain.destroy
      render json: { status: "success", message: "Domain deleted" }
    end
  end
end
