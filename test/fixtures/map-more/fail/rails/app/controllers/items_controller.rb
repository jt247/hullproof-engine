class ItemsController < ApplicationController
  def index
    limit = params[:limit].to_i
    render json: Item.limit(limit)
  end
end
