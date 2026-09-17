# frozen_string_literal: true

module Api
  module Clients
    # class for validating input data from the user
    class Validator
      attr_accessor :params

      SCHEMA = {
        'type' => 'object',
        'properties' => {
          'address' => {
            'type' => 'string',
            'format' => 'ipv4'
          },
          'address_ipv6' => {
            'type' => 'string',
            'format' => 'ipv6'
          },
          'private_key' => { 'type' => 'string' },
          'public_key' => { 'type' => 'string' },
          'preshared_key' => { 'type' => 'string' },
          'allowed_ips' => { 'type' => 'string' },
          'enable' => { 'type' => 'boolean' },
          'data' => { 'type' => 'object' }
        },
        'additionalProperties' => false
      }.freeze

      # These three reach wg0.conf verbatim, so 'type' => 'string' is not enough
      # on its own: a value containing a newline would add directives of its own
      # to that file. Checked in Ruby rather than as a JSON Schema 'pattern',
      # because the gem's patterns are unanchored and \n-unaware.
      KEY_PARAMS = %w[private_key public_key preshared_key].freeze

      def initialize(params)
        @params = params
      end

      def validate!
        result = JSON::Validator.validate!(SCHEMA, params)
        validate_key_params!
        result
      end

      private

      def validate_key_params!
        KEY_PARAMS.each do |key_param|
          value = params[key_param]

          next if value.nil? || WireGuard::KeyGenerator.valid_key?(value)

          raise Errors::InvalidKeyMaterialError
        end
      end
    end
  end
end
