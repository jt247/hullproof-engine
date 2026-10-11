class Admin::UsersController < ApplicationController
  def role
    user = User.find(params[:id])
    user.update(role: params[:role])
    head :no_content
  end
end
