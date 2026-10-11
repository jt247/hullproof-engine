class ApplicationController < ActionController::API
  before_action :authenticate_request

  private

  def authenticate_request
    token = request.headers["Authorization"].to_s.split(" ").last
    payload = JsonWebToken.decode(token)
    @current_user = User.find(payload[:user_id])
  rescue StandardError
    render json: { error: "unauthorized" }, status: :unauthorized
  end

  def current_user
    @current_user
  end
end
