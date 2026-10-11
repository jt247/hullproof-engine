class ImportsController < ApplicationController
  def create
    page = Net::HTTP.get(URI(params[:url]))
    render plain: page
  end
end
