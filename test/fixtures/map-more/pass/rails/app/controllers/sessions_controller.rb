class SessionsController < ApplicationController
  skip_before_action :authenticate_request
  rate_limit to: 10, within: 1.minute, only: :create

  def create
    credentials = params.require(:session).permit(:email, :password)
    user = User.find_by(email: credentials[:email])
    if user&.authenticate(credentials[:password])
      target = params[:next].to_s
      redirect_to(target.start_with?("/") && !target.start_with?("//") ? target : "/")
    else
      head :unauthorized
    end
  end
end
