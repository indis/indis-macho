require 'rubygems'
require 'bundler/setup'

RSpec.configure do |config|
  config.treat_symbols_as_metadata_keys_with_true_values = true
  config.run_all_when_everything_filtered = true
  config.filter_run :focus
  if ENV['SKIP_OSX_INTEGRATION']
    config.filter_run_excluding :requires_osx => true
  end
end
