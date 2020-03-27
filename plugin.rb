# frozen_string_literal: true
# name: discourse-jwt
# about: JSON Web Tokens Auth Provider
# version: 0.1
# author: Robin Ward

gem "discourse-omniauth-jwt", "0.0.3", require: false

require 'omniauth/jwt'

class JWTAuthenticator < Auth::ManagedAuthenticator
  def name
    'jwt'
  end

  def register_middleware(omniauth)
    public_key_string = "-----BEGIN RSA PRIVATE KEY-----\n#{GlobalSetting.jwt_secret}\n-----END RSA PRIVATE KEY-----"
    puts public_key_string
    public_key_string.gsub!(/\s/,'\n')
    puts public_key_string
    public_key = OpenSSL::PKey::RSA.new(public_key_string)
    omniauth.provider :jwt,
                      name: 'jwt',
                      uid_claim: 'userId',
                      required_claims: ['userId', 'groups'],
                      info_map: {'name' => 'userId'},
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:secret] = public_key
                        opts[:auth_url] = GlobalSetting.jwt_auth_url
                        opts[:algorithm] = GlobalSetting.jwt_algorithm
                      }
  end

  def enabled?
    # Check the global setting for backwards-compatibility.
    # When this plugin used only global settings, there was no separate enable setting
    SiteSetting.jwt_enabled || GlobalSetting.try(:jwt_auth_url)
  end
end

auth_provider authenticator: JWTAuthenticator.new
