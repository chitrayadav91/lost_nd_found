class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable, password_length: 1..72

  validates_presence_of :email
  validates_uniqueness_of :email, case_sensitive: false
  validates_format_of :email, with: /@/

  def self.authenticate(login, pass)
    user = self.find_by_email login.downcase
    if user
      unless user.valid_password?(pass)
        user.errors.add(" Password", "is invalid") unless user.valid_password?(pass)
      end
      return user
    end
  end


end
