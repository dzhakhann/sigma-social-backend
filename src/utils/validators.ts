export const validateEmail = (email: string): boolean => {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
};

export const validateUsername = (username: string): boolean => {
  return username.length >= 3 && username.length <= 50;
};

export const validatePassword = (password: string): boolean => {
  return password.length >= 8;
};

export const validateContent = (content: string): boolean => {
  return content.length > 0 && content.length <= 5000;
};