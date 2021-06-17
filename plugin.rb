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
    public_key = OpenSSL::PKey::RSA.new(public_key_string)
    omniauth.provider :jwt,
                      name: 'jwt',
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:algorithm] = 'RS256'
                        opts[:uid_claim] = 'userId'
                        opts[:required_claims] = ['email', 'userId', 'username']
                        opts[:secret] = public_key
                        opts[:info_map] = {'email' => 'email', 'username' => 'username', 'name' => 'name'}
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
