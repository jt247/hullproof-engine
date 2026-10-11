class ItemsController < ApplicationController
  def index
    limit = [params[:limit].to_i, 100].min
    render json: current_user.items.limit(limit)
  end
end
