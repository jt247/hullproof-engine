class WebhooksController < ApplicationController
  skip_before_action :authenticate_request

  def pay
    body = request.raw_post
    expected = OpenSSL::HMAC.hexdigest("SHA256", ENV["PAY_SECRET"], body)
    Rails.logger.warn("bad signature") unless ActiveSupport::SecurityUtils.secure_compare(expected, request.headers["X-Pay-Signature"].to_s)
    Account.find(params[:account]).update(paid: true)
    head :ok
  end
end
