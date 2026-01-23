# frozen_string_literal: true

module LegacyAPI
  class DomainsController < BaseController
    before_action :set_server

    def create
      p = api_params
      name = p["name"].to_s.strip.downcase

      if name.empty?
        render_error "DomainNameMissing", message: "Domain name is missing"
        return
      end

      existing = @server.domains.find_by(name: name)
      if existing
        render_error "DomainNameExists", message: "Domain name already exists"
        return
      end

      domain = Domain.new
      domain.server = @server
      domain.name = name
      domain.verification_method = "DNS"
      domain.owner_type = "Server"
      domain.owner_id = @server.id
      domain.verified_at = Time.now

      if domain.save
        render_success({ name: domain.name })
      else
        msg = domain.errors.full_messages.first || "Validation failed"
        if msg == "Name is invalid"
          render_error "InvalidDomainName"
        else
          render_error "ValidationError", message: msg
        end
      end
    end

    def query
      p = api_params
      name = p["name"].to_s.strip.downcase

      if name.empty?
        render_error "DomainNameMissing", message: "Domain name is missing"
        return
      end

      domain = @server.domains.find_by(name: name)
      if domain.nil?
        render_error "DomainNotFound", message: "The domain not found"
      else
        render_success({ name: domain.name })
      end
    end

    def check
      p = api_params
      name = p["name"].to_s.strip.downcase

      if name.empty?
        render_error "DomainNameMissing", message: "Domain name is missing"
        return
      end

      domain = @server.domains.find_by(name: name)
      if domain.nil?
        render_error "DomainNotFound", message: "The domain not found"
        return
      end

      domain.check_dns(:manual)
      render_success({ name: domain.name })
    end

    def delete
      p = api_params
      name = p["name"].to_s.strip.downcase

      if name.empty?
        render_error "DomainNameMissing", message: "Domain name is missing"
        return
      end

      domain = @server.domains.find_by(name: name)
      if domain.nil?
        render_error "DomainNotFound", message: "The domain not found"
        return
      end

      if domain.delete
        render_success({ message: "Domain deleted successfully" })
      else
        render_error "DomainNotDeleted", message: "Domain could not be deleted"
      end
    end

    private

    def set_server
      @server = @current_credential && @current_credential.server
      if @server.nil?
        render_error "AccessDenied", message: "Must be authenticated as a server."
      end
    end
  end
end
