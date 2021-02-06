namespace Application.Models.Views.Account
{
	public class SignInViewModel
	{
		#region Fields

		private SignInForm _form;

		#endregion

		#region Properties

		public virtual SignInForm Form
		{
			get => this._form ??= new SignInForm();
			set => this._form = value;
		}

		#endregion
	}
}