# frozen_string_literal: true

module LegacyAPI
  class DomainsController < BaseController

    def create
      name = params[:name].to_s.strip.downcase

      if name.empty?
        render json: { status: "error", message: "Domain name is required" }, status: 422
        return
      end

      server = @server
      if server.nil?
        render json: { status: "error", message: "Server not found for API key" }, status: 401
        return
      end

      domain = Domain.where("lower(name) = ?", name)
                     .where(server_id: server.id)
                     .first

      if domain
        render json: { status: "success", data: serialize_domain(domain) }
        return
      end

      domain = Domain.new
      domain.name = name
      domain.server_id = server.id if domain.respond_to?(:server_id=)
      domain.verification_method = "DNS" if domain.respond_to?(:verification_method=)
      domain.owner_type = "Server" if domain.respond_to?(:owner_type=)
      domain.owner_id = server.id if domain.respond_to?(:owner_id=)

      if domain.save
        render json: { status: "success", data: serialize_domain(domain) }, status: 201
      else
        render json: { status: "error", message: domain.errors.full_messages.join(", ") }, status: 422
      end
    end

    def query
      name = params[:name].to_s.strip.downcase

      if name.empty?
        render json: { status: "error", message: "Domain name is required" }, status: 422
        return
      end

      server = @server
      if server.nil?
        render json: { status: "error", message: "Server not found for API key" }, status: 401
        return
      end

      domain = find_domain(name)

      unless domain
        render json: { status: "error", message: "Domain not found" }, status: 404
        return
      end

      render json: { status: "success", data: serialize_domain(domain) }
    end

    def check
      name = params[:name].to_s.strip.downcase

      if name.empty?
        render json: { status: "error", message: "Domain name is required" }, status: 422
        return
      end

      server = @server
      if server.nil?
        render json: { status: "error", message: "Server not found for API key" }, status: 401
        return
      end

      domain = find_domain(name)

      unless domain
        render json: { status: "error", message: "Domain not found" }, status: 404
        return
      end

      begin
        domain.check_dns(:manual) if domain.respond_to?(:check_dns)
      rescue
      end

      data = serialize_domain(domain)
      data[:dns] = serialize_dns(domain)

      render json: { status: "success", data: data }
    end

    def delete
      name = params[:name].to_s.strip.downcase

      if name.empty?
        render json: { status: "error", message: "Domain name is required" }, status: 422
        return
      end

      server = @server
      if server.nil?
        render json: { status: "error", message: "Server not found for API key" }, status: 401
        return
      end

      domain = find_domain(name)

      unless domain
        render json: { status: "error", message: "Domain not found" }, status: 404
        return
      end

      domain.destroy
      render json: { status: "success", message: "Domain deleted" }
    end

    private

    def find_domain(name)
      server = @server
      return nil unless server

      domain = Domain.where("lower(name) = ?", name)
                     .where(server_id: server.id)
                     .first
      return domain if domain

      orphan = Domain.where("lower(name) = ?", name)
                     .where(server_id: nil)
                     .first

      if orphan
        begin
          orphan.server_id = server.id if orphan.respond_to?(:server_id=)
          orphan.save(validate: false)
        rescue
        end
        return orphan
      end

      nil
    end

    def serialize_domain(domain)
      out = {
        id: domain.id,
        name: domain.name,
        server_id: domain.server_id,
        verification_method: domain.verification_method
      }

      out[:created_at] = domain.created_at if domain.respond_to?(:created_at)
      out[:updated_at] = domain.updated_at if domain.respond_to?(:updated_at)
      out[:return_path_domain] = domain.return_path_domain if domain.respond_to?(:return_path_domain)
      out[:dkim_identifier] = domain.dkim_identifier if domain.respond_to?(:dkim_identifier)
      out[:dkim_key] = {} if domain.respond_to?(:dkim_key)

      out
    end

    def serialize_dns(domain)
      dns = {}

      begin
        if domain.respond_to?(:check_spf_record)
          spf = domain.check_spf_record
          dns[:spf] = { expected: spf[:expected] } if spf.is_a?(Hash)
        end
      rescue
      end

      begin
        if domain.respond_to?(:check_dkim_record)
          dkim = domain.check_dkim_record
          dns[:dkim] = {
            host: dkim[:host],
            expected: dkim[:expected]
          }.compact if dkim.is_a?(Hash)
        end
      rescue
      end

      begin
        if domain.respond_to?(:check_return_path_record)
          rp = domain.check_return_path_record
          dns[:return_path] = {
            host: rp[:host],
            expected_target: rp[:expected]
          }.compact if rp.is_a?(Hash)
        end
      rescue
      end

      dns
    end
  end
end
