FROM php:8.4-fpm-alpine

RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
    && php composer-setup.php --install-dir=/usr/bin \
    && php -r "unlink('composer-setup.php');" \
    && mv /usr/bin/composer.phar /usr/bin/composer
RUN apk add postgresql-dev npm \
    && docker-php-ext-install pdo pdo_pgsql

COPY . /var/www
RUN composer install

RUN npm install \
    && npm run build

WORKDIR /var/www