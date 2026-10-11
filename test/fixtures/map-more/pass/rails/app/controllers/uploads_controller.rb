class UploadsController < ApplicationController
  ALLOWED_TYPES = ["image/png", "image/jpeg"].freeze
  MAX_BYTES = 5.megabytes

  def create
    file = params.require(:upload).permit(:file)[:file]
    return head(:payload_too_large) if file.size > MAX_BYTES
    return head(:unsupported_media_type) unless ALLOWED_TYPES.include?(file.content_type)

    File.binwrite(Rails.root.join("uploads", SecureRandom.uuid), file.read)
    head :created
  end
end
