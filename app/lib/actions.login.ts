'use server';

import { z } from 'zod';
import { signIn } from '@/auth';
import { AuthError } from 'next-auth';

const FormLoginSchema = z.object({
  email: z.coerce.string().email("This is not a valid email."),
  password: z.string().min(6),
});

export type LoginState = {
  errors?: {
    email?: string[];
    passsword?: string[];
  };
  message?: string | null;
};

export async function authenticate(
  prevState: LoginState,
  formData: FormData,
) {

  const validatedFields = FormLoginSchema.safeParse({
    email: formData.get('email'),
    password: formData.get('password'),
  });

  // If form validation fails, return errors early. Otherwise, continue.
  if (!validatedFields.success) {
    return {
      errors: validatedFields.error.flatten().fieldErrors,
      message: 'Missing Fields. Failed to Authenticate.',
    };
  }

  try {
    await signIn('credentials', formData);
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case 'CredentialsSignin':
          return { message: 'Invalid credentials.'};
        default:
          return { message: 'Something went wrong.'};
      }
    }
    throw error;
  }
}
