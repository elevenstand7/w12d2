class User < ApplicationRecord
  has_secure_password

  validates :username, :email, :session_token, presence: true, uniqueness: true
  validates :username, length: { in: 3..30 }, format: { without: URI::MailTo::EMAIL_REGEXP, message: "can't be an email"}
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }, length:{in: 3..255}
  validates :password, length:{in: 6..255}, allow_nil:true

  before_validation :ensure_session_token

  def self.find_by_credentials(credential, password)
    if credential =~ URI::MailTo::EMAIL_REGEXP
      field = :email
    else
      field = :username
    end
    user = User.find_by(field => credential)
    user&.authenticate(password)? user : nil
  end

  def reset_session_token!
    self.update!(session_token: generate_unique_session_token)
    self.session_token
  end

  def generate_unique_session_token
    while true
        token = SecureRandom.base64
      return token unless User.exists?(session_token: token)
    end
  end

  def ensure_session_token
    self.session_token ||= generate_unique_session_token;
  end


end
