class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, and :timeoutable
  devise :database_authenticatable, :registerable, :omniauthable,
         :recoverable, :rememberable, :trackable, :validatable

  has_many :identities, dependent: :destroy

  validates :name, presence: true

  def self.find_for_oauth(auth, signed_in_resource = nil)
    # Get the identity and user if they exist
    identity = Identity.find_for_oauth(auth)

    # If a signed_in_resource is provided it always overrides the existing user
    # to prevent the identity being locked with accidently created accounts.
    # Note that this may leave zombie accounts (with no associated identity) which
    # can be cleaned up at a later date.
    user = signed_in_resource ? signed_in_resource : identity.user

    # Create the user if needed
    if user.nil?
      email = auth.info.email
      user = User.where(email: email).first if email

      # Create the user if it's a new registration
      if user.nil?
        user = User.new(
          name: auth.info.name,
          email: email,
          #password: Devise.friendly_token[0,20],
          profile: auth.extra.raw_info.to_yaml
        )
        user.identities << identity
        user.save!
      end
    end

    user.update_attribute(:profile, auth.extra.raw_info.to_yaml) unless user.profile?

    # Associate the identity with the user if needed
    if identity.user != user
      identity.user = user
      identity.save!
    end
    user
  end

  def password_required?
    super && identities.empty?
  end

  def update_with_password(params, *options)
    if encrypted_password.blank?
      update_attributes(params, *options)
    else
      super
    end
  end
end
