# frozen_string_literal: true

RSpec.describe WireGuard::ServerConfigUpdater do
  subject(:update) { described_class.update }

  let(:wg_conf_path) { "#{Settings.wg_path}/wg0.conf" }
  let(:wg_json_path) { "#{Settings.wg_path}/wg0.json" }

  before do
    allow(Kernel).to receive(:system).with('wg-quick down wg0').and_return(true)
    allow(Kernel).to receive(:system).with('wg-quick up wg0').and_return(true)
    create_conf_file('spec/fixtures/wg0.json')
  end

  after do
    FileUtils.rm_rf(wg_json_path)
    FileUtils.rm_rf(wg_conf_path)
  end

  context 'when the stored peers are well formed' do
    before do
      update
    end

    it 'creates the correct config file for the wireguard server' do
      config = File.read(wg_conf_path)

      expect(config).to eq(File.read('spec/fixtures/wg0.conf'))
    end

    it 'restarts the wireguard server' do
      expect(Kernel).to have_received(:system).with('wg-quick up wg0')
    end
  end

  # NOTE: Unreachable while every write path validates its input — which is the
  # point. This is the backstop that keeps a future path from quietly reopening
  # the hole, so it is exercised by poisoning the stored config directly.
  context 'when a stored peer value carries a newline' do
    %w[public_key preshared_key address address_ipv6].each do |field|
      context "when it is #{field}" do
        before do
          json_config = JSON.parse(File.read(wg_json_path))
          peer = json_config['configs']['1']
          peer[field] = "#{peer[field]}\nAllowedIPs = 0.0.0.0/0"
          File.write(wg_json_path, JSON.pretty_generate(json_config))
        end

        it 'refuses to build the config' do
          expect { update }.to raise_error(Errors::InvalidKeyMaterialError)
        end

        it 'writes no wireguard config file' do
          expect { update }.to raise_error(Errors::InvalidKeyMaterialError)

          expect(File.exist?(wg_conf_path)).to be(false)
        end

        it 'does not restart the wireguard server' do
          expect { update }.to raise_error(Errors::InvalidKeyMaterialError)

          expect(Kernel).not_to have_received(:system)
        end
      end
    end
  end
end
