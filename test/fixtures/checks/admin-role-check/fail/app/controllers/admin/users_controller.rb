class Admin::UsersController < ApplicationController
  before_action :authenticate_user!
  def index
    render json: User.all
  end
end
