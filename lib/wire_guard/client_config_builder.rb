# frozen_string_literal: true

module WireGuard
  # The class generates a config file for the client
  class ClientConfigBuilder
    # NOTE: The first address of each pool, which offsets count from. The
    # server holds offset 1; clients start at 2.
    POOL_BASE = {
      'address' => IPAddr.new(Settings.wg_default_address.gsub('x', '0')),
      'address_ipv6' => IPAddr.new(Settings.wg_default_address_6.gsub('x', '0'))
    }.freeze

    CONNECTING_CLIENT_LIMIT = Settings.connecting_client_limit.to_i
    CONNECTING_CLIENT_LIMIT_6 = Settings.connecting_client_limit_6.to_i
    WG_ALLOWED_IPS = Settings.wg_allowed_ips

    FIRST_CLIENT_OFFSET = 2

    attr_reader :config

    # NOTE: The smaller pool decides, and its last offset is left unused: on
    # IPv4 it is the broadcast address. Upstream counted it as usable, so a
    # full /24 handed out 10.8.0.255.
    def self.last_client_offset
      [2**(32 - CONNECTING_CLIENT_LIMIT), 2**(128 - CONNECTING_CLIENT_LIMIT_6)].min - 2
    end

    def self.available_addresses_count
      last_client_offset - FIRST_CLIENT_OFFSET + 1
    end

    # NOTE: `resting` holds IPv4 addresses released too recently to reissue.
    # See WireGuard::Server#resting_addresses.
    def initialize(configs, params, resting: [])
      @configs = configs
      @params = params || {}
      @resting = resting
      validate_public_key!
      check_availability_of_space!
      @config = build_config(@params)
    end

    private

    attr_reader :configs, :params, :resting

    # NOTE: The client generates its own keypair and supplies only the public
    # half, so no private key is generated, transmitted, or stored here.
    def build_config(params) # rubocop:disable Metrics/MethodLength
      offset = free_offset

      {
        id: configs['last_id'] + 1,
        address: address_at(offset, 'address'),
        address_ipv6: address_at(offset, 'address_ipv6'),
        public_key: params['public_key'],
        preshared_key: KeyGenerator.wg_genpsk,
        allowed_ips: WG_ALLOWED_IPS,
        enable: true,
        data: params.except('public_key')
      }
    end

    def validate_public_key!
      return if KeyGenerator.valid_key?(params['public_key'])

      raise Errors::InvalidPublicKeyError
    end

    def check_availability_of_space!
      return if clients.size < self.class.available_addresses_count

      raise Errors::ConnectionLimitExceededError
    end

    # NOTE: One offset for both families, so a peer's IPv4 and IPv6 addresses
    # sit at the same position in their pools. A node maps each position to a
    # fixed block of outbound source ports, and a peer whose two addresses
    # fell at different positions would leave through two different blocks.
    #
    # The lowest offset that is free in both pools and not resting. Resting
    # offsets are skipped rather than waited for: an address released moments
    # ago is still attributable to its previous holder.
    def free_offset
      unavailable = taken_offsets | resting.map { |address| offset_of(address, 'address') }

      (FIRST_CLIENT_OFFSET..self.class.last_client_offset).find { |offset| !unavailable.include?(offset) } or
        raise Errors::ConnectionLimitExceededError
    end

    def taken_offsets
      clients.flat_map do |config|
        [offset_of(config['address'], 'address'), offset_of(config['address_ipv6'], 'address_ipv6')]
      end
    end

    def clients
      # NOTE: This is necessary in order to maintain backward compatibility
      # with those who still have the "last_address" field in the config.
      configs.except('last_id').values.grep(Hash)
    end

    def offset_of(address, ip_version_key)
      IPAddr.new(address).to_i - POOL_BASE[ip_version_key].to_i
    end

    def address_at(offset, ip_version_key)
      base = POOL_BASE[ip_version_key]

      IPAddr.new(base.to_i + offset, base.family).to_s
    end
  end
end
