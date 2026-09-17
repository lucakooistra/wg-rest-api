# frozen_string_literal: true

module WireGuard
  # class for generating WireGuard keys
  class KeyGenerator
    # A base64-encoded 32 byte key — public, private or preshared alike: 42 free
    # characters, a 43rd whose two low bits are zero, and one padding character.
    #
    # NOTE: \A and \z rather than ^ and $ on purpose. Key material is written
    # verbatim into wg0.conf, and line anchors would let a value containing a
    # newline smuggle extra directives into that file.
    KEY_FORMAT = %r{\A[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=\z}

    class << self
      def valid_key?(key)
        key.is_a?(String) && key.match?(KEY_FORMAT)
      end

      def wg_genkey
        `wg genkey`.gsub(/\n$/, '')
      end

      def wg_pubkey(wg_genkey)
        `echo #{wg_genkey} | wg pubkey`.gsub(/\n$/, '')
      end

      def wg_genpsk
        `wg genpsk`.gsub(/\n$/, '')
      end
    end
  end
end
