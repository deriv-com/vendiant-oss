'use client';

import React, { useState, useRef, useEffect } from 'react';

interface DropdownItem {
  value: string;
  text: string;
  data?: any;
}

interface SearchableDropdownProps {
  placeholder: string;
  items: DropdownItem[];
  value?: string;
  onChange?: (item: DropdownItem | null) => void;
  disabled?: boolean;
}

const SearchableDropdown: React.FC<SearchableDropdownProps> = ({
  placeholder,
  items,
  value,
  onChange,
  disabled = false
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedItem, setSelectedItem] = useState<DropdownItem | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Find selected item based on value prop
  useEffect(() => {
    if (value) {
      const item = items.find(item => item.value === value);
      setSelectedItem(item || null);
      setSearchTerm(item?.text || '');
    } else {
      setSelectedItem(null);
      setSearchTerm('');
    }
  }, [value, items]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        // Reset search term to selected item text or empty
        setSearchTerm(selectedItem?.text || '');
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [selectedItem]);

  // Filter items based on search term
  const filteredItems = items.filter(item =>
    item.text.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.value.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(e.target.value);
    setIsOpen(true);
  };

  const handleItemSelect = (item: DropdownItem) => {
    setSelectedItem(item);
    setSearchTerm(item.text);
    setIsOpen(false);
    onChange?.(item);
  };

  const handleInputFocus = () => {
    setIsOpen(true);
  };

  const handleClear = () => {
    setSelectedItem(null);
    setSearchTerm('');
    setIsOpen(false);
    onChange?.(null);
    inputRef.current?.focus();
  };

  return (
    <div className="searchable-dropdown" ref={dropdownRef}>
      <div className="dropdown-input-container">
        <input
          ref={inputRef}
          type="text"
          className={`form-control searchable-input ${disabled ? 'disabled' : ''}`}
          placeholder={placeholder}
          value={searchTerm}
          onChange={handleInputChange}
          onFocus={handleInputFocus}
          disabled={disabled}
        />
        {selectedItem && !disabled && (
          <button
            type="button"
            className="dropdown-clear-btn"
            onClick={handleClear}
            title="Clear selection"
          >
            <i className="fas fa-times"></i>
          </button>
        )}
        <button
          type="button"
          className={`dropdown-toggle-btn ${disabled ? 'disabled' : ''}`}
          onClick={() => !disabled && setIsOpen(!isOpen)}
          disabled={disabled}
        >
          <i className={`fas fa-chevron-${isOpen ? 'up' : 'down'}`}></i>
        </button>
      </div>
      
      {isOpen && !disabled && (
        <div className="dropdown-menu">
          {filteredItems.length > 0 ? (
            filteredItems.map((item, index) => (
              <div
                key={index}
                className={`dropdown-item ${selectedItem?.value === item.value ? 'selected' : ''}`}
                onClick={() => handleItemSelect(item)}
              >
                {item.text}
              </div>
            ))
          ) : (
            <div className="dropdown-item disabled">
              No results found
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SearchableDropdown; 