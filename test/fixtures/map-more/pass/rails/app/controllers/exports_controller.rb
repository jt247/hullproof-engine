class ExportsController < ApplicationController
  def index
    render json: [{ id: current_user.id, email: current_user.email }]
  end
end
