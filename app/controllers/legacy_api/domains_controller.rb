# frozen_string_literal: true

module LegacyAPI
  class DomainsController < BaseController

    def query
      name = api_params["name"].to_s.strip.downcase
      if name.empty?
        render_error "DomainNameMissing"
        return
      end

      domain = @current_credential.server.domains.find_by(name: name)
      unless domain
        render_error "NotFound"
        return
      end

      domain.check_dns(:manual)

      render_success serialize_dns(domain)
    end

    private

    def serialize_dns(domain)
      spf = domain.dns_results[:spf]
      dkim = domain.dns_results[:dkim]
      rp  = domain.dns_results[:return_path]

      {
        domain: domain.name,
        last_checked_at: domain.dns_checked_at,

        spf: {
          status: spf[:status],
          exists: spf[:status] == "valid",
          record: domain.spf_record,
          message: spf[:message]
        },

        dkim: {
          status: dkim[:status],
          selector: domain.dkim_identifier,
          host: "#{domain.dkim_identifier}._domainkey.#{domain.name}",
          value: domain.dkim_public_key,
          message: dkim[:message]
        },

        return_path: {
          status: rp[:status],
          host: domain.return_path_domain,
          expected: domain.return_path_target,
          actual: rp[:actual],
          message: rp[:message]
        }
      }
    end
  end
end

