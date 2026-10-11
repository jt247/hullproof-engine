class ImportsController < ApplicationController
  ALLOWED_HOSTS = ["example.com"].freeze

  def create
    url = params.require(:import).permit(:url)[:url]
    return head(:bad_request) unless ALLOWED_HOSTS.include?(URI(url).host)

    render plain: Net::HTTP.get(URI(url))
  end
end
