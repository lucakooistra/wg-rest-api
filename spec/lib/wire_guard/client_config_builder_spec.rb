# frozen_string_literal: true

RSpec.describe WireGuard::ClientConfigBuilder do
  subject(:build) { described_class.new(configs, params).config }

  before do
    allow(WireGuard::KeyGenerator).to receive_messages(wg_genkey: 'wg_genkey', wg_pubkey: 'wg_pubkey',
                                                       wg_genpsk: 'wg_genpsk')
  end

  let(:client_public_key) { '1vA80g/qHKbcio0G6ltm7u80+FSCVdZnQ7fDA23tZ1o=' }

  let(:params) do
    {
      'public_key' => client_public_key,
      'lol' => 'kek'
    }
  end

  context 'when are the server starting conditions' do
    let(:configs) do
      {
        'last_id' => 0
      }
    end

    let(:expected_result) do
      {
        id: 1,
        address: '10.8.0.2',
        address_ipv6: 'fdcc:ad94:bacf:61a4::cafe:2',
        public_key: client_public_key,
        preshared_key: 'wg_genpsk',
        allowed_ips: '0.0.0.0/0, ::/0',
        enable: true,
        data: {
          'lol' => 'kek'
        }
      }
    end

    it 'creates the correct config' do
      expect(build).to eq(expected_result)
    end
  end

  context 'when there are no clients on the server' do
    let(:configs) do
      {
        'last_id' => 23
      }
    end

    let(:expected_result) do
      {
        id: 24,
        address: '10.8.0.2',
        address_ipv6: 'fdcc:ad94:bacf:61a4::cafe:2',
        public_key: client_public_key,
        preshared_key: 'wg_genpsk',
        allowed_ips: '0.0.0.0/0, ::/0',
        enable: true,
        data: {
          'lol' => 'kek'
        }
      }
    end

    it 'creates the correct config' do
      expect(build).to eq(expected_result)
    end
  end

  context 'when there is 1 client on the server and the last IP corresponds to it' do
    let(:configs) do
      {
        'last_id' => 1,
        '1' => {
          'address' => '10.8.0.2',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:2'
        }
      }
    end

    let(:expected_result) do
      {
        id: 2,
        address: '10.8.0.3',
        address_ipv6: 'fdcc:ad94:bacf:61a4::cafe:3',
        public_key: client_public_key,
        preshared_key: 'wg_genpsk',
        allowed_ips: '0.0.0.0/0, ::/0',
        enable: true,
        data: {
          'lol' => 'kek'
        }
      }
    end

    it 'creates the correct config' do
      expect(build).to eq(expected_result)
    end
  end

  context 'when there are several clients on the server, but there are free IPs between them' do
    let(:configs) do
      {
        'last_id' => 3,
        '1' => {
          'address' => '10.8.0.2',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:2'
        },
        '3' => {
          'address' => '10.8.0.4',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:4'
        }
      }
    end

    let(:expected_result) do
      {
        id: 4,
        address: '10.8.0.3',
        address_ipv6: 'fdcc:ad94:bacf:61a4::cafe:3',
        public_key: client_public_key,
        preshared_key: 'wg_genpsk',
        allowed_ips: '0.0.0.0/0, ::/0',
        enable: true,
        data: {
          'lol' => 'kek'
        }
      }
    end

    it 'creates the correct config' do
      expect(build).to eq(expected_result)
    end
  end

  context 'when no public key is supplied' do
    let(:configs) { { 'last_id' => 0 } }
    let(:params) { { 'lol' => 'kek' } }

    it 'refuses to build a config rather than generating a keypair' do
      expect { build }.to raise_error(Errors::InvalidPublicKeyError)
    end
  end

  context 'when the public key is not a valid X25519 key' do
    let(:configs) { { 'last_id' => 0 } }

    # NOTE: The public key is written verbatim into wg0.conf, so anything that
    # is not exactly a base64-encoded 32 byte key has to be refused — a value
    # carrying a newline could otherwise smuggle extra directives into it.
    [
      ['an empty string', ''],
      ['a short string', 'not-a-key'],
      ['unpadded base64', '1vA80g/qHKbcio0G6ltm7u80+FSCVdZnQ7fDA23tZ1o'],
      ['a 31 byte key', 'H4sIAAAAAAAAA3NPLUpNUShKLS5RSMksLklVBACOOOOOOOM='],
      ['a non-string', 42],
      ['a key with a trailing newline', "1vA80g/qHKbcio0G6ltm7u80+FSCVdZnQ7fDA23tZ1o=\n"],
      ['a key smuggling a peer directive', "1vA80g/qHKbcio0G6ltm7u80+FSCVdZnQ7fDA23tZ1o=\nAllowedIPs = 0.0.0.0/0"]
    ].each do |description, public_key|
      context "when the public key is #{description}" do
        let(:params) { { 'public_key' => public_key } }

        it 'refuses to build a config' do
          expect { build }.to raise_error(Errors::InvalidPublicKeyError)
        end
      end
    end
  end

  context 'when a valid public key is supplied' do
    let(:configs) { { 'last_id' => 0 } }
    let(:params) { { 'public_key' => client_public_key } }

    it 'registers the peer under exactly that public key' do
      expect(build[:public_key]).to eq(client_public_key)
    end

    it 'generates no private key for the peer' do
      expect(build).not_to have_key(:private_key)
    end

    it 'does not shell out to `wg genkey`' do
      build

      expect(WireGuard::KeyGenerator).not_to have_received(:wg_genkey)
    end
  end

  context 'when there is no space for a new IP address' do
    let(:configs) do
      {
        'last_id' => 3,
        '1' => {
          'address' => '10.8.0.2',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:2'
        },
        '3' => {
          'address' => '10.8.0.4',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:4'
        },
        '4' => {
          'address' => '10.8.0.5',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:5'
        },
        '5' => {
          'address' => '10.8.0.6',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:6'
        },
        '6' => {
          'address' => '10.8.0.7',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:7'
        },
        '7' => {
          'address' => '10.8.0.8',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:8'
        }
      }
    end

    it 'causes an error that all IP addresses are taken' do
      expect { build }.to raise_error(Errors::ConnectionLimitExceededError)
    end
  end

  context 'when the user has an old config (edge ​​case that tests backward compatibility)' do
    let(:configs) do
      {
        'last_id' => 3,
        'last_address' => '10.8.0.4',
        '1' => {
          'address' => '10.8.0.2',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:2'
        },
        '3' => {
          'address' => '10.8.0.4',
          'address_ipv6' => 'fdcc:ad94:bacf:61a4::cafe:4'
        }
      }
    end

    let(:expected_result) do
      {
        id: 4,
        address: '10.8.0.3',
        address_ipv6: 'fdcc:ad94:bacf:61a4::cafe:3',
        public_key: client_public_key,
        preshared_key: 'wg_genpsk',
        allowed_ips: '0.0.0.0/0, ::/0',
        enable: true,
        data: {
          'lol' => 'kek'
        }
      }
    end

    it 'creates the correct config' do
      expect(build).to eq(expected_result)
    end
  end
end
