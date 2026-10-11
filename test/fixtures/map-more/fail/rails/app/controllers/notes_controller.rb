class NotesController < ApplicationController
  skip_before_action :authenticate_request, only: [:create]

  def create
    note = Note.create(title: params[:title], owner_id: params[:owner_id])
    render json: note
  end

  def destroy
    Note.find(params[:id]).destroy
    head :no_content
  end
end
