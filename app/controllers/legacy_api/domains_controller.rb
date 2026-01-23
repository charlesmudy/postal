# app/controllers/legacy_api/domains_controller.rb
# frozen_string_literal: true

module LegacyAPI
  class DomainsController < BaseController

    def query
      domain = find_domain
      return unless domain

      render_success serialize_dns(domain)
    end

    def check
      domain = find_domain
      return unless domain

      domain.check_dns(:manual)
      render_success serialize_dns(domain)
    end

    def delete
      domain = find_domain
      return unless domain

      domain.destroy
      render_success message: "Domain deleted successfully"
    end

    private

    def find_domain
      name = api_params["name"].to_s.strip.downcase
      if name.empty?
        render_error "DomainNameMissing"
        return nil
      end

      domain = @current_credential.server.domains.find_by(name: name)
      unless domain
        render_error "NotFound"
        return nil
      end

      domain
    end

    def serialize_dns(domain)
      results = domain.dns_results

      {
        domain: domain.name,
        last_checked_at: domain.dns_checked_at,

        spf: {
          status: results[:spf][:status],
          record: domain.spf_record,
          message: results[:spf][:message]
        },

        dkim: {
          status: results[:dkim][:status],
          selector: domain.dkim_identifier,
          host: "#{domain.dkim_identifier}._domainkey.#{domain.name}",
          value: domain.dkim_public_key,
          message: results[:dkim][:message]
        },

        return_path: {
          status: results[:return_path][:status],
          host: domain.return_path_domain,
          expected: domain.return_path_target,
          actual: results[:return_path][:actual],
          message: results[:return_path][:message]
        }
      }
    end
  end
end
