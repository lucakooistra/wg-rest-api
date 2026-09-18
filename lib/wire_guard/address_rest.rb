# frozen_string_literal: true

module WireGuard
  # NOTE: Tunnel addresses released too recently to be reissued.
  #
  # A released address is not handed out again straight away. Closed
  # connections linger in the kernel's connection tracking for minutes after a
  # session ends, and an abuse report names a time to the nearest minute at
  # best, so an address reissued at once would put two holders inside one
  # report's margin of error. Resting it keeps "who held this address at
  # 14:32" a question with one answer.
  #
  # Only the address and when it was released are kept, and only while it
  # rests — stored in wg0.json under 'released'. Nothing here says who held it.
  class AddressRest
    PERIOD = Settings.address_rest_period.to_i

    # `released` maps an IPv4 address to the Unix time it was released at.
    def initialize(released)
      cutoff = Time.now.to_i - PERIOD

      @released = (released || {}).select { |_address, released_at| released_at > cutoff }
    end

    def addresses
      released.keys
    end

    # The record to store once `address` is released: every address still
    # resting, plus this one. Those whose rest is over are dropped here, so the
    # record never outgrows the addresses it is currently holding back.
    def rest(address)
      released.merge(address => Time.now.to_i)
    end

    private

    attr_reader :released
  end
end
