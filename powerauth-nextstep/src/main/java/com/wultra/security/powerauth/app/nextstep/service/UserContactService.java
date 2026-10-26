/*
 * PowerAuth Web Flow and related software components
 * Copyright (C) 2021 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.powerauth.app.nextstep.service;

import com.wultra.core.audit.base.Audit;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.security.powerauth.app.nextstep.converter.UserContactConverter;
import com.wultra.security.powerauth.app.nextstep.repository.UserIdentityRepository;
import com.wultra.security.powerauth.app.nextstep.repository.catalogue.RepositoryCatalogue;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.UserContactEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.UserIdentityEntity;
import com.wultra.security.powerauth.app.nextstep.service.catalogue.ServiceCatalogue;
import com.wultra.security.powerauth.lib.nextstep.model.entity.UserContactDetail;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserContactAlreadyExistsException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserContactNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateUserContactRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.DeleteUserContactRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.GetUserContactListRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.UpdateUserContactRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.CreateUserContactResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.DeleteUserContactResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.GetUserContactListResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.UpdateUserContactResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This service handles persistence of user contacts.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class UserContactService {

    private final Logger logger = LoggerFactory.getLogger(UserContactService.class);
    private static final String AUDIT_TYPE_USER_IDENTITY = "USER_IDENTITY";

    private final UserIdentityRepository userIdentityRepository;
    private final ServiceCatalogue serviceCatalogue;
    private final Audit audit;

    private final UserContactConverter userContactConverter = new UserContactConverter();

    /**
     * User contact service constructor.
     * @param repositoryCatalogue Repository catalogue.
     * @param serviceCatalogue Service catalogue.
     * @param audit Audit interface.
     */
    @Autowired
    public UserContactService(RepositoryCatalogue repositoryCatalogue, @Lazy ServiceCatalogue serviceCatalogue, Audit audit) {
        this.serviceCatalogue = serviceCatalogue;
        this.userIdentityRepository = repositoryCatalogue.getUserIdentityRepository();
        this.audit = audit;
    }

    /**
     * Create contact for a user identity.
     * @param request Create user contact request.
     * @return Create user contact response
     * @throws UserNotFoundException Thrown when user identity is not found.
     * @throws UserContactAlreadyExistsException Thrown when user contact already exists.
     */
    @Transactional
    public CreateUserContactResponse createUserContact(CreateUserContactRequest request) throws UserNotFoundException, UserContactAlreadyExistsException {
        // Serialize with contact verification and other contact changes of the same user
        userIdentityRepository.findAndLockByUserId(request.getUserId());
        final UserIdentityLookupService userIdentityLookupService = serviceCatalogue.getUserIdentityLookupService();
        UserIdentityEntity user = userIdentityLookupService.findUser(request.getUserId());
        final Set<UserContactEntity> contacts = user.getContacts();
        final Optional<UserContactEntity> contactOptional = contacts.stream().filter(c -> c.getName().equals(request.getContactName()) && c.getType().equals(request.getContactType())).findFirst();
        if (contactOptional.isPresent()) {
            throw new UserContactAlreadyExistsException("User contact already exists: " + request.getContactName() + ", user ID: " + user.getUserId() + ", type: " + request.getContactType());
        }
        final UserContactEntity contact = new UserContactEntity();
        contact.setUser(user);
        contact.setName(request.getContactName());
        contact.setType(request.getContactType());
        contact.setValue(request.getContactValue());
        contact.setPrimary(request.isPrimary());
        contact.setTimestampCreated(new Date());
        if (request.getVerificationMethod() != null) {
            contact.setVerificationMethod(request.getVerificationMethod());
            contact.setTimestampVerified(new Date());
        }
        user.getContacts().add(contact);
        // Ensure primary contacts are unique
        ensurePrimaryContactsAreUnique(user);
        user = userIdentityRepository.save(user);
        logger.debug("User contact was created, user ID: {}, contact name: {}", user.getUserId(), contact.getName());
        audit.info("User contact was created", AuditDetail.builder()
                .type(AUDIT_TYPE_USER_IDENTITY)
                .param("userId", user.getUserId())
                .param("contactName", contact.getName())
                .build());
        final CreateUserContactResponse response = new CreateUserContactResponse();
        response.setUserId(user.getUserId());
        response.setContactName(contact.getName());
        response.setContactType(contact.getType());
        response.setContactValue(contact.getValue());
        response.setPrimary(contact.isPrimary());
        response.setVerificationMethod(contact.getVerificationMethod());
        response.setTimestampVerified(contact.getTimestampVerified());
        return response;
    }

    /**
     * Get contacts for user identity.
     * @param request Get user contact list request.
     * @return Get user contact list response.
     * @throws UserNotFoundException Thrown when user identity is not found.
     */
    @Transactional
    public GetUserContactListResponse getUserContactList(GetUserContactListRequest request) throws UserNotFoundException {
        final UserIdentityLookupService userIdentityLookupService = serviceCatalogue.getUserIdentityLookupService();
        UserIdentityEntity user = userIdentityLookupService.findUser(request.getUserId());
        Set<UserContactEntity> contacts = user.getContacts();
        GetUserContactListResponse response = new GetUserContactListResponse();
        response.setUserId(user.getUserId());
        for (UserContactEntity contact : contacts) {
            UserContactDetail contactDetail = userContactConverter.fromEntity(contact);
            response.getContacts().add(contactDetail);
        }
        return response;
    }

    /**
     * Update contact for a user identity.
     * @param request Update user contact request.
     * @return Update user contact response.
     * @throws UserNotFoundException Thrown when user identity is not found.
     * @throws UserContactNotFoundException Thrown when user contact is not found.
     */
    @Transactional
    public UpdateUserContactResponse updateUserContact(UpdateUserContactRequest request) throws UserNotFoundException, UserContactNotFoundException {
        // Serialize with contact verification and other contact changes of the same user
        userIdentityRepository.findAndLockByUserId(request.getUserId());
        final UserIdentityLookupService userIdentityLookupService = serviceCatalogue.getUserIdentityLookupService();
        UserIdentityEntity user = userIdentityLookupService.findUser(request.getUserId());
        Set<UserContactEntity> contacts = user.getContacts();
        Optional<UserContactEntity> contactOptional = contacts.stream().filter(c -> c.getName().equals(request.getContactName()) && c.getType().equals(request.getContactType())).findFirst();
        if (contactOptional.isEmpty()) {
            throw new UserContactNotFoundException("User contact not found: " + request.getContactName() + ", user ID: " + user.getUserId() + ", type: " + request.getContactType());
        }
        final UserContactEntity contact = contactOptional.get();
        final boolean valueChanged = !Objects.equals(contact.getValue(), request.getContactValue());
        if (valueChanged) {
            // Invalidate pending verifications of the old value so they cannot be revived by changing the value back
            serviceCatalogue.getContactVerificationService().invalidatePendingVerifications(contact);
        }
        contact.setUser(user);
        contact.setName(request.getContactName());
        contact.setType(request.getContactType());
        contact.setValue(request.getContactValue());
        contact.setPrimary(request.isPrimary());
        contact.setTimestampLastUpdated(new Date());
        // A changed value is unverified unless the caller asserts a verification method for it
        if (request.getVerificationMethod() != null && (valueChanged || !request.getVerificationMethod().equals(contact.getVerificationMethod()))) {
            contact.setVerificationMethod(request.getVerificationMethod());
            contact.setTimestampVerified(new Date());
        } else if (valueChanged) {
            contact.setVerificationMethod(null);
            contact.setTimestampVerified(null);
        }
        // Ensure primary contacts are unique
        ensurePrimaryContactsAreUnique(user);
        user = userIdentityRepository.save(user);
        logger.debug("User contact was updated, user ID: {}, contact name: {}", user.getUserId(), contact.getName());
        audit.info("User contact was updated", AuditDetail.builder()
                .type(AUDIT_TYPE_USER_IDENTITY)
                .param("userId", user.getUserId())
                .param("contactName", contact.getName())
                .build());
        UpdateUserContactResponse response = new UpdateUserContactResponse();
        response.setUserId(user.getUserId());
        response.setContactName(contact.getName());
        response.setContactType(contact.getType());
        response.setContactValue(contact.getValue());
        response.setPrimary(contact.isPrimary());
        response.setVerificationMethod(contact.getVerificationMethod());
        response.setTimestampVerified(contact.getTimestampVerified());
        return response;
    }

    /**
     * Delete contact for a user identity.
     * @param request Delete user contact request.
     * @return Delete user contact response.
     * @throws UserNotFoundException Thrown when user identity is not found.
     * @throws UserContactNotFoundException Thrown when user contact is not found.
     */
    @Transactional
    public DeleteUserContactResponse deleteUserContact(DeleteUserContactRequest request) throws UserNotFoundException, UserContactNotFoundException {
        // Serialize with contact verification and other contact changes of the same user
        userIdentityRepository.findAndLockByUserId(request.getUserId());
        final UserIdentityLookupService userIdentityLookupService = serviceCatalogue.getUserIdentityLookupService();
        UserIdentityEntity user = userIdentityLookupService.findUser(request.getUserId());
        Set<UserContactEntity> contacts = user.getContacts();
        Optional<UserContactEntity> contactOptional = contacts.stream().filter(c -> c.getName().equals(request.getContactName()) && c.getType().equals(request.getContactType())).findFirst();
        if (contactOptional.isEmpty()) {
            throw new UserContactNotFoundException("No user contact found: " + request.getContactName() + ", user ID: " + user.getUserId() + ", type: " + request.getContactType());
        }
        final UserContactEntity contact = contactOptional.get();
        serviceCatalogue.getContactVerificationService().invalidatePendingVerifications(contact);
        user.getContacts().remove(contact);
        user = userIdentityRepository.save(user);
        logger.debug("User contact was deleted, user ID: {}, contact name: {}", user.getUserId(), contact.getName());
        audit.info("User contact was deleted", AuditDetail.builder()
                .type(AUDIT_TYPE_USER_IDENTITY)
                .param("userId", user.getUserId())
                .param("contactName", contact.getName())
                .build());
        DeleteUserContactResponse response = new DeleteUserContactResponse();
        response.setUserId(user.getUserId());
        response.setContactName(request.getContactName());
        response.setContactType(request.getContactType());
        return response;
    }

    /**
     * Mark a user contact as verified using the given verification method.
     * @param userId User identity identifier.
     * @param contactName Contact name.
     * @param contactType Contact type.
     * @param method Verification method that confirmed the contact.
     * @throws UserNotFoundException Thrown when user identity is not found.
     * @throws UserContactNotFoundException Thrown when user contact is not found.
     */
    @Transactional
    public void markContactVerified(String userId, String contactName, ContactType contactType, ContactVerificationMethod method) throws UserNotFoundException, UserContactNotFoundException {
        final UserIdentityEntity user = serviceCatalogue.getUserIdentityLookupService().findUser(userId);
        final UserContactEntity contact = user.getContacts().stream()
                .filter(c -> c.getName().equals(contactName) && c.getType().equals(contactType))
                .findFirst()
                .orElseThrow(() -> new UserContactNotFoundException("User contact not found: " + contactName + ", user ID: " + userId + ", type: " + contactType));
        contact.setVerificationMethod(method);
        contact.setTimestampVerified(new Date());
        userIdentityRepository.save(user);
        logger.debug("User contact was verified, user ID: {}, contact name: {}", userId, contactName);
    }

    /**
     * In case multiple contacts are set as primary for the same contact type, the contact with newest created or last updated
     * date should be primary. This method is not transactional.
     */
    public void ensurePrimaryContactsAreUnique(UserIdentityEntity user) {
        Set<UserContactEntity> contacts = user.getContacts();
        Set<ContactType> contactTypes = contacts.stream().map(UserContactEntity::getType).collect(Collectors.toSet());
        for (ContactType ct : contactTypes) {
            // Find all primary contacts per contact type
            List<UserContactEntity> contactListPrimary = contacts.stream()
                    .filter(c -> c.getType().equals(ct))
                    .filter(UserContactEntity::isPrimary)
                    .toList();
            if (contactListPrimary.size() > 1) {
                // Multiple primary contacts exists, find the newest one by created or last updated date
                Date maxDate = new Date(0);
                for (UserContactEntity c : contactListPrimary) {
                    if (c.getTimestampCreated() != null && c.getTimestampCreated().after(maxDate)) {
                        maxDate = c.getTimestampCreated();
                    }
                    if (c.getTimestampLastUpdated() != null && c.getTimestampLastUpdated().after(maxDate)) {
                        maxDate = c.getTimestampLastUpdated();
                    }
                }
                UserContactEntity primaryContact = null;
                for (UserContactEntity c : contactListPrimary) {
                    if ((c.getTimestampCreated() != null && c.getTimestampCreated().equals(maxDate))
                            || (c.getTimestampLastUpdated() != null && c.getTimestampLastUpdated().equals(maxDate))) {
                        // This is the effectively primary contact, keep it primary
                        primaryContact = c;
                        break;
                    }
                }
                // Update primary contacts which were created earlier, they are no longer primary
                for (UserContactEntity c : contactListPrimary) {
                    if (c.equals(primaryContact)) {
                        continue;
                    }
                    c.setPrimary(false);
                }
            }
        }
    }

}