# frozen_string_literal: true

RSpec.describe Api::Clients::Validator do
  subject(:validate) { described_class.new(params).validate! }

  let(:key) { '1vA80g/qHKbcio0G6ltm7u80+FSCVdZnQ7fDA23tZ1o=' }

  context 'when all parameters are valid' do
    let(:params) do
      {
        'address' => '1.2.3.4',
        'private_key' => 'wABihfmnf2qBPFPErkF6hryFlCWMaezP/7DHDnp4s3U=',
        'public_key' => '1vA80g/qHKbcio0G6ltm7u80+FSCVdZnQ7fDA23tZ1o=',
        'preshared_key' => '2H4hdH3iwrGVNMmLKH+VsBe/QsC1TblG+mukcwOLimA=',
        'allowed_ips' => 'sda',
        'enable' => false,
        'data' => {}
      }
    end

    it 'return true' do
      expect(validate).to be(true)
    end
  end

  context 'when parameters are empty' do
    let(:params) do
      {}
    end

    it 'return true' do
      expect(validate).to be(true)
    end
  end

  context 'when all parameters are valid but there are extra ones' do
    let(:params) do
      {
        'address' => '1.2.3.4',
        'private_key' => 'wABihfmnf2qBPFPErkF6hryFlCWMaezP/7DHDnp4s3U=',
        'public_key' => '1vA80g/qHKbcio0G6ltm7u80+FSCVdZnQ7fDA23tZ1o=',
        'preshared_key' => '2H4hdH3iwrGVNMmLKH+VsBe/QsC1TblG+mukcwOLimA=',
        'allowed_ips' => 'sda',
        'enable' => false,
        'data' => {},
        'extra' => 123
      }
    end

    it 'raises a validation error' do
      expect { validate }.to raise_error(JSON::Schema::ValidationError)
    end
  end

  context 'when one parameter is not valid' do
    let(:params) do
      {
        'enable' => 'false'
      }
    end

    it 'raises a validation error' do
      expect { validate }.to raise_error(JSON::Schema::ValidationError)
    end
  end

  # NOTE: These three reach wg0.conf verbatim. A value carrying a newline could
  # append an AllowedIPs line, or a whole second [Peer] block, to that file.
  %w[private_key public_key preshared_key].each do |key_param|
    context "when #{key_param} is not a valid WireGuard key" do
      {
        'a bare word' => ->(_key) { 'not-a-key' },
        'an empty string' => ->(_key) { '' },
        'unpadded base64' => ->(key) { key.delete_suffix('=') },
        'a key with a trailing newline' => ->(key) { "#{key}\n" },
        'a key smuggling an AllowedIPs directive' => ->(key) { "#{key}\nAllowedIPs = 0.0.0.0/0, ::/0" },
        'a key smuggling a whole peer block' => ->(key) { "#{key}\n[Peer]\nPublicKey = #{key}" }
      }.each do |description, build_value|
        context "when it is #{description}" do
          let(:params) { { key_param => build_value.call(key) } }

          it 'raises a key material error' do
            expect { validate }.to raise_error(Errors::InvalidKeyMaterialError)
          end
        end
      end
    end
  end

  context 'when there were several parameters and they were valid' do
    let(:params) do
      {
        'preshared_key' => '2H4hdH3iwrGVNMmLKH+VsBe/QsC1TblG+mukcwOLimA=',
        'enable' => false,
        'data' => {}
      }
    end

    it 'return true' do
      expect(validate).to be(true)
    end
  end
end
