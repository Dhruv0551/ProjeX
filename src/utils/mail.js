// import { verify } from "jsonwebtoken";
import Mailgen from 'mailgen';
import nodemailer from 'nodemailer';

const sendEmail = async function (options) {
  const mailGenerator = new Mailgen({
    theme: 'default',
    product: {
      name: 'Task Manager',
      link: 'https://google.com',
    },
  });

  const emailText = mailGenerator.generate(options.MailgenContent);
  const emailHTML = mailGenerator.generate(options.MailgenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAIL_SMTP_HOST,
    port: process.env.MAIL_SMTP_PORT,
    auth: {
      user: process.env.MAIL_SMTP_USER,
      pass: process.env.MAIL_SMTP_PASS,
    },
  });

  const mail = {
    from: 'test@example.com',
    to: options.email,
    subject: options.subject,
    text: emailText,
    html: emailHTML,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error(
      "Email Service Failed! Please ensure You've given Valid Credentials in the ENV",
      error,
    );
  }
};

const emailVerificationMailGen = (username, verificationURL) => {
  return {
    body: {
      name: username,
      intro: 'Welcome to our App! We are Happy to have you Onboard',
      action: {
        instruction:
          'To verify Your Email please click on the following button 👇',
        button: {
          color: '#1f1f1f',
          text: 'Verify Your Email',
          link: verificationURL,
        },
      },
      outro:
        'Need help or have any Question? Just contact our customer Service',
    },
  };
};

const forgotPasswordMailGen = (username, verificationURL) => {
  return {
    body: {
      name: username,
      intro: 'We got The request to reset Your Passeord',
      action: {
        instruction:
          'To reset Your Password please click on the following button 👇',
        button: {
          color: '#085fabff',
          text: 'Reset Password',
          link: verificationURL,
        },
      },
      outro:
        'Need help or have any Question? Just contact our customer Service',
    },
  };
};

export { emailVerificationMailGen, forgotPasswordMailGen, sendEmail };
