class Admin::UsersController < ApplicationController
  before_action :require_admin
  def index
    render json: User.all
  end
end
