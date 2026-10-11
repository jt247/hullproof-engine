Rails.application.routes.draw do
  post "/login", to: "sessions#create"
  post "/webhooks/pay", to: "webhooks#pay"
  resources :notes, only: [:create, :destroy]
  get "/api/export", to: "exports#index"
  get "/api/items", to: "items#index"
  post "/api/import", to: "imports#create"
  post "/api/upload", to: "uploads#create"

  namespace :admin do
    resources :users, only: [] do
      member do
        post :role
      end
    end
  end
end
