class Api::V1::UsersController < ApplicationController
  before_action :authenticate_request!, except: [:create, :login]

  def create
    user = User.new(email: params[:email], password: params[:password])
    if user.save
      render json: {status: 'User created successfully'}, status: :created
    else
      render json: { errors: user.errors.full_messages }, status: :bad_request
    end
  end

  def login
    if user = User.authenticate(params[:email], params[:password])
        auth_token = JsonWebToken.encode({user_id: user.id})
        render json: {auth_token: auth_token}, status: :ok
    else
      render json: {error: 'Invalid username / password'}, status: :unauthorized
    end
  end

  def show
    render json: @current_user, status: :created
  end

  private

  def user_params
    params.require(:user).permit(:email, :password, :password_confirmation)
  end
end