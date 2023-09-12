class User < ApplicationRecord
  has_secure_password

  validates :username, :email, :session_token, presence: true, uniqueness: true
  validates :username, length: { in: 3..30 }, format: { without: URI::MailTo::EMAIL_REGEXP, message: "can't be an email"}
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }, length:{in: 3..255}
  validates :password, length:{in: 6..255}, allow_nil:true

  before_validation :ensure_session_token

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
