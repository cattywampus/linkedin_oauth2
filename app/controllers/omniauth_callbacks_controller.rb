class OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def linkedin
    @user = User.find_for_oauth(env['omniauth.auth'], current_user)

    if @user.persisted?
      sign_in_and_redirect @user, event: :authentication
      set_flash_message(:notice, :success, kind: 'LinkedIn') if is_navigational_format?
    else
      session["devise.#{provider}_data"] = env['omniauth.auth']
      redirect_to new_user_registration_url
    end
  end
end
