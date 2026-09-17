# frozen_string_literal: true

module Errors
  class InvalidKeyMaterialError < BaseError # rubocop:disable Style/Documentation
    def message
      'Keys must be base64-encoded 32-byte WireGuard keys'
    end
  end
end
