# frozen_string_literal: true

module Errors
  class InvalidPublicKeyError < BaseError # rubocop:disable Style/Documentation
    def message
      'A base64-encoded 32-byte WireGuard public key is required to create a client'
    end
  end
end
