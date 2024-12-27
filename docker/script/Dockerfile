FROM php:8.4-fpm-alpine

RUN apk add postgresql-dev \
    && docker-php-ext-install pdo pdo_pgsql

WORKDIR /var/www

COPY . /var/www

RUN chmod 777 /var/www/shell.sh

CMD ["sh", "/var/www/shell.sh"]