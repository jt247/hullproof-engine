class SessionsController < ApplicationController
  skip_before_action :authenticate_request

  def create
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      redirect_to params[:next]
    else
      head :unauthorized
    end
  end
end
