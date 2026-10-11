class UploadsController < ApplicationController
  def create
    file = params[:file]
    File.binwrite(Rails.root.join("uploads", file.original_filename), file.read)
    head :created
  end
end
