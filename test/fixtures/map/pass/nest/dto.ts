import { IsEmail, IsIn, IsString, MaxLength, MinLength } from 'class-validator';

export class CreateNoteDto {
  @IsString() @MinLength(1) @MaxLength(200) title!: string;
}

export class SetRoleDto {
  @IsString() id!: string;
  @IsIn(['member', 'admin']) role!: string;
}
