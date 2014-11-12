class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  def default_url_options
    if Rails.env.production?
      { host: 'radiant-basin-1445.herokuapp.com' }
    else
      {}
    end
  end

  def ensure_signup_complete
    return if action_name == 'finish_signup'

    if current_user && !current_user.email_verified?
      redirect_to finish_signup_path(current_user)
    end
  end
end
