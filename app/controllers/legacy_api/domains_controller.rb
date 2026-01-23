# frozen_string_literal: true

module LegacyAPI
  class DomainsController < BaseController

    def create
      name = params[:name].to_s.strip.downcase

      if name.empty?
        return render json: { status: "error", message: "Domain name is required" }, status: 422
      end

      domain = Domain.find_by(name: name, server: @server)
      if domain
        return render json: {
          status: "success",
          data: serialize_domain(domain)
        }
      end

      domain = Domain.new
      domain.server = @server
      domain.name = name

      # Tracking domains use TXT ownership verification in the UI.
      # Keep method as DNS so Postal shows the normal flow.
      domain.verification_method = "DNS" if domain.respond_to?(:verification_method)

      # Owner fields exist in Postal tracking domains
      if domain.respond_to?(:owner_type=) && domain.respond_to?(:owner_id=)
        domain.owner_type = "Server"
        domain.owner_id = @server.id
      end

      if domain.save
        render json: {
          status: "success",
          data: serialize_domain(domain)
        }
      else
        render json: {
          status: "error",
          message: domain.errors.full_messages.join(", ")
        }, status: 422
      end
    end

    def query
      name = params[:name].to_s.strip.downcase
      domain = Domain.find_by(name: name, server: @server)

      unless domain
        return render json: { status: "error", message: "Domain not found" }, status: 404
      end

      render json: {
        status: "success",
        data: serialize_domain(domain)
      }
    end

    def check
      name = params[:name].to_s.strip.downcase
      domain = Domain.find_by(name: name, server: @server)

      unless domain
        return render json: { status: "error", message: "Domain not found" }, status: 404
      end

      # Run Postal’s DNS check so you get the same expectations your UI uses
      checks = DomainDNSChecker.check(domain)

      # Optional: if the TXT ownership record is now valid, auto-mark verified.
      # This removes the need for the user to click “Verify TXT record”.
      # We try to detect a pass condition from the checker response safely.
      if domain.respond_to?(:verified_at) && domain.verified_at.nil?
        if ownership_verified_from_checks?(checks)
          domain.update_column(:verified_at, Time.now)
        end
      end

      render json: {
        status: "success",
        data: serialize_domain(domain).merge(dns: checks)
      }
    end

    def delete
      name = params[:name].to_s.strip.downcase
      domain = Domain.find_by(name: name, server: @server)

      unless domain
        return render json: { status: "error", message: "Domain not found" }, status: 404
      end

      domain.destroy

      render json: {
        status: "success",
        data: { message: "Domain deleted" }
      }
    end

    private

    def serialize_domain(domain)
      payload = {
        id: domain.id,
        name: domain.name,
        server_id: domain.respond_to?(:server_id) ? domain.server_id : @server.id,
        verification_method: domain.respond_to?(:verification_method) ? domain.verification_method : nil,
        created_at: domain.respond_to?(:created_at) ? domain.created_at&.iso8601 : nil,
        updated_at: domain.respond_to?(:updated_at) ? domain.updated_at&.iso8601 : nil,
        verified_at: domain.respond_to?(:verified_at) ? domain.verified_at&.iso8601 : nil
      }.compact

      if domain.respond_to?(:return_path_domain) && domain.return_path_domain.present?
        payload[:return_path_domain] = domain.return_path_domain
      end

      if domain.respond_to?(:dkim_identifier) && domain.dkim_identifier.present?
        payload[:dkim_identifier] = domain.dkim_identifier
      end

      payload
    end

    def ownership_verified_from_checks?(checks)
      return false unless checks.is_a?(Hash)

      # Try common shapes without breaking if Postal changes the response.
      # If DomainDNSChecker returns a verification section, prefer it.
      verification = checks["verification"] || checks[:verification]
      if verification.is_a?(Hash)
        ok = verification["ok"]
        ok = verification[:ok] if ok.nil?
        return true if ok == true
      end

      # Fallback: if no explicit verification field exists, do nothing.
      false
    end
  end
end
