class NotesController < ApplicationController
  def create
    note = current_user.notes.create(note_params)
    render json: note
  end

  def destroy
    current_user.notes.find(params[:id]).destroy
    head :no_content
  end

  private

  def note_params
    params.require(:note).permit(:title)
  end
end
