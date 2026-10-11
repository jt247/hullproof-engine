class ExportsController < ApplicationController
  skip_before_action :authenticate_request

  def index
    render json: User.all.map { |u| { id: u.id, email: u.email } }
  end
end
