class Admin::UsersController < Admin::BaseController
  def role
    user = User.find(params[:id])
    user.update(role: params[:role])
    AuditLog.create!(actor_id: current_user.id, action: "set_role", target_id: user.id)
    head :no_content
  end
end
